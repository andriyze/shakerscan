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


def reserve_active_enrichment_budget(
    active_max_seconds: Any,
    *,
    primary_enabled: bool = True,
    reserve_enrichment: bool = True,
) -> tuple[float | None, float]:
    """Split active time into primary probe and post-active enrichment budgets.

    SQLi/XSS are the primary active probes. They should not be allowed to consume
    the entire shard budget because SQLMap, NoSQL, stored-XSS, DOM-XSS, and
    auxiliary injection checks are the modules that often turn broad probing into
    actionable proof. Very small budgets are left untouched.

    ``reserve_enrichment=False`` gives the FULL budget to primary SQLi/XSS: used by
    coverage shards, where the discover-once recon backbone already runs the
    enrichment modules once, so each zero-rediscovery shard should spend its whole
    budget on per-endpoint SQLi/XSS breadth instead of re-reserving ~20% for
    enrichment it won't meaningfully add.
    """
    if not primary_enabled:
        return active_max_seconds, 0.0
    if not reserve_enrichment:
        try:
            return (max(0.0, float(active_max_seconds)) if active_max_seconds is not None else None), 0.0
        except (TypeError, ValueError):
            return None, 0.0
    if active_max_seconds is None:
        return None, 0.0
    try:
        total = max(0.0, float(active_max_seconds))
    except (TypeError, ValueError):
        return None, 0.0
    if total < 90.0:
        return total, 0.0

    reserve_floor = 30.0 if total < 600.0 else 90.0
    reserve = max(reserve_floor, total * 0.20)
    reserve = min(reserve, 600.0)
    # Keep at least a minute for primary probes when the user gave a finite
    # active budget.
    reserve = min(reserve, max(0.0, total - 60.0))
    primary = max(0.0, total - reserve)
    return primary, reserve


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
    """Record a skip reason using the report fields existing consumers expect.

    `sqlmap_skipped` is a list-of-dicts so per-candidate detail is preserved
    across multiple calls (also written directly by SQLMap-specific code).
    Every other module's skip key is a flat reason string. Both shapes are
    deduplicated so repeated calls do not overwrite an earlier richer reason
    or balloon the list with identical entries.
    """
    skip_key = ACTIVE_ENRICHMENT_SKIP_KEYS.get(module, f"{module}_skipped")
    if skip_key == "sqlmap_skipped":
        entry = {
            "skip_reason": reason,
            "candidate_reason": candidate_reason or "post_active_budget",
        }
        if details:
            entry.update(details)
        existing = active_block.setdefault(skip_key, [])
        for prior in existing:
            if (
                prior.get("skip_reason") == entry["skip_reason"]
                and prior.get("candidate_reason") == entry["candidate_reason"]
            ):
                return
        existing.append(entry)
        return

    # Flat-string shape: keep the first recorded reason. Later identical calls
    # are no-ops; later *different* reasons would silently overwrite, so prefer
    # the original (callers should prefer the earliest, most specific signal).
    if skip_key not in active_block:
        active_block[skip_key] = reason
