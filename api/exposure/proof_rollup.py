"""Exposure proof counts from the finding view's canonical proof projection."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

try:
    from finding_routes.router import finding_proof_fields
except ModuleNotFoundError:  # package import in host-side tests
    from ..finding_routes.router import finding_proof_fields


def active_finding_proof_counts(rows: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str], dict[str, int]]:
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"verified": 0, "needs_verification": 0, "investigator_verified": 0}
    )
    for source in rows:
        finding = dict(source)
        if finding.get("status") != "active":
            continue
        kind = "target" if finding.get("target_id") else "ai"
        asset_id = finding.get("target_id") or finding.get("ai_target_id")
        if not asset_id:
            continue
        item = counts[(kind, str(asset_id))]
        if finding_proof_fields(finding)["is_verified"]:
            item["verified"] += 1
            if finding.get("tool") in {"autonomous_workflow", "bola"}:
                item["investigator_verified"] += 1
        elif (
            finding.get("last_verification_verdict") in {None, "inconclusive", "error", "likely_vulnerable"}
            or finding.get("analyst_verdict") in {"needs_review", "retest_needed"}
        ):
            item["needs_verification"] += 1
    return dict(counts)
