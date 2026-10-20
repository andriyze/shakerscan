"""Derive a completed Scan's endpoint inventory worklist from its own durable discovery.

A canonical Scan writes its discovery output as ``discover.*`` action receipts and observation
manifests and never emits the old ``active_checks.active_worklist`` report block. Reading only
that block left every canonical Scan -- including an on-demand ASM recon whose whole purpose is
to refresh the inventory -- without persisted endpoints. Render the receipts exactly as the
parallel discovery hand-off does so both paths derive endpoints one way.
"""

from __future__ import annotations

from typing import Any, Mapping

from .continuation import (
    discovery_shard_endpoint_worklist,
    load_discovery_shard_receipts,
)
from .jobs import target_binding_from_payload
from .worker_validation import validate_execution_plan

ASM_RECON_RUN_KIND = "asm_recon"


def inventory_source(options: Mapping[str, Any] | None) -> str:
    """Inventory provenance for a standalone Scan's discovered endpoints."""
    run_kind = str((options or {}).get("run_kind") or "")
    return "recon" if run_kind == ASM_RECON_RUN_KIND else "scan"


async def scan_inventory_worklist(
    pool: Any,
    result: Mapping[str, Any] | None,
    *,
    scan_id: str,
    target_url: str,
    options: Mapping[str, Any] | None,
) -> tuple[list[str], str]:
    """Return ``(worklist, source)`` for the per-target endpoint inventory.

    A report that still carries ``active_checks.active_worklist`` keeps it. Otherwise a
    canonical Scan (frozen target binding plus a valid execution plan) is harvested from its
    own discovery receipts, bounded by the plan's endpoint budget. Anything else yields an
    empty worklist; it never widens scope, since the surface projection admits only the
    binding's origins.
    """
    options = options or {}
    source = inventory_source(options)
    legacy = ((result or {}).get("active_checks") or {}).get("active_worklist")
    if legacy:
        return list(legacy), source
    raw_binding = options.get("_canonical_target_binding")
    if not raw_binding:
        return [], source
    try:
        binding = target_binding_from_payload(raw_binding)
        max_endpoints = validate_execution_plan(options).budget.max_endpoints
    except (TypeError, ValueError):  # not canonical authority: no durable discovery to read
        return [], source
    async with pool.acquire() as conn:
        statuses, observations = await load_discovery_shard_receipts(conn, scan_id=scan_id)
    if not statuses:
        return [], source
    worklist, _meta = discovery_shard_endpoint_worklist(
        scan_id=scan_id,
        target=binding,
        target_url=target_url,
        options=options,
        action_statuses=statuses,
        observations=observations,
        max_endpoints=max_endpoints,
    )
    return worklist, source
