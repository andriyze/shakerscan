"""Canonical asset identity is independent from the executor that produced a scan.

The compatibility device reference selects device finding/policy persistence. A
populated canonical target_id must never route device output into Web DAST/ASM.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ExecutionTargetRefs:
    canonical_target_id: str | None
    web_target_id: str | None
    ai_target_id: str | None
    device_target_id: str | None


def execution_target_refs(row: Mapping[str, Any]) -> ExecutionTargetRefs:
    canonical = str(row['target_id']) if row.get('target_id') else None
    device = str(row['device_target_id']) if row.get('device_target_id') else None
    ai = str(row['ai_target_id']) if row.get('ai_target_id') else None
    return ExecutionTargetRefs(canonical or device, canonical if not device and not ai else None, ai, device)
