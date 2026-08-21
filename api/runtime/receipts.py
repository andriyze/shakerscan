"""Typed capability execution receipt contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping
from uuid import uuid4


_TERMINAL_RESERVATION_STATES = frozenset({"committed", "released", "failed"})
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


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
    budget_reservation_id: str | None = None
    budget_reservation_state: str | None = None
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
        digest = str(self.input_digest or "").strip().lower()
        if not _HEX_64_RE.fullmatch(digest):
            raise ValueError("input_digest must be 64 lowercase hex characters")
        object.__setattr__(self, "input_digest", digest)
        reservation_id = str(self.budget_reservation_id or "").strip() or None
        reservation_state = str(self.budget_reservation_state or "").strip().lower() or None
        if reservation_state and not reservation_id:
            raise ValueError("budget_reservation_state requires budget_reservation_id")
        if reservation_id and reservation_state not in _TERMINAL_RESERVATION_STATES:
            raise ValueError("capability receipt requires a terminal budget reservation state")
        object.__setattr__(self, "budget_reservation_id", reservation_id)
        object.__setattr__(self, "budget_reservation_state", reservation_state)

    def canonical_dict(self) -> dict[str, Any]:
        """Stable receipt material used for persistence and hashing."""
        return asdict(self)

    @property
    def receipt_hash(self) -> str:
        encoded = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def public_dict(self) -> dict[str, Any]:
        return {**self.canonical_dict(), "receipt_hash": self.receipt_hash}
