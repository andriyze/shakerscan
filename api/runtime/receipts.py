"""Typed capability execution receipt contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4


@dataclass(frozen=True)
class CapabilityReceipt:
    capability_name: str
    adapter_name: str
    adapter_version: str
    target_id: str
    status: str
    input_digest: str
    parser_version: str
    receipt_id: str = field(default_factory=lambda: str(uuid4()))
    scan_id: str | None = None
    hunt_id: str | None = None
    worker_id: str | None = None
    scope_receipt_id: str | None = None
    approval_receipt_id: str | None = None
    partial: bool = False
    timed_out: bool = False
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    redacted_execution: Mapping[str, Any] = field(default_factory=dict)
    budget_reserved: Mapping[str, int] = field(default_factory=dict)
    budget_consumed: Mapping[str, int] = field(default_factory=dict)
    output_artifact_id: str | None = None

    def __post_init__(self) -> None:
        if not self.scan_id and not self.hunt_id:
            raise ValueError("capability receipt must belong to a scan or hunt")
        if self.partial and self.status == "completed":
            raise ValueError("partial execution cannot claim completed status")
        if self.timed_out and not self.partial:
            raise ValueError("timed out execution must be marked partial")

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)
