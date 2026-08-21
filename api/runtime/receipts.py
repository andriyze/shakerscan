"""Typed, redacted, content-addressed capability execution receipts.

A receipt is the immutable bridge between a server-authorized capability call, the
budget reservation that covered it, the worker that executed it, and the evidence
objects produced by the parser. Planner/model prose is never accepted as receipt
material and common secret-bearing values are redacted before hashing or exposure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping, Sequence
from uuid import uuid4

from .budgets import BUDGET_DIMENSIONS


_TERMINAL_RESERVATION_STATES = frozenset({"committed", "released", "failed"})
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_STATUS_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_-])(?:authorization|auth|bearer|cookie|credential|password|passwd|"
    r"private[_-]?key|secret|signature|token|api[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
_INLINE_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(bearer)\s+[^\s,;]+"),
    re.compile(
        r"(?i)(\b(?:authorization|cookie|set-cookie|x-api-key|api-key)\s*[:=]\s*)"
        r"[^\s,;]+"
    ),
    re.compile(
        r"(?i)([?&](?:access_token|token|api_key|apikey|secret|password|signature)=)"
        r"[^&#\s]+"
    ),
    re.compile(r"(://)[^/@\s]+@"),
)


def _normalize_budget(values: Mapping[str, int], *, allow_zero: bool) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for raw_kind, raw_amount in dict(values or {}).items():
        kind = str(raw_kind or "").strip()
        if kind not in BUDGET_DIMENSIONS:
            raise ValueError(f"unknown budget dimension: {kind}")
        if isinstance(raw_amount, bool):
            raise ValueError(f"budget amount for {kind} must be an integer")
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"budget amount for {kind} must be an integer") from exc
        if amount < 0:
            raise ValueError(f"budget amount for {kind} must be non-negative")
        if amount or allow_zero:
            normalized[kind] = amount
    return normalized


def _redact_string(value: str) -> str:
    redacted = value
    for index, pattern in enumerate(_INLINE_SECRET_PATTERNS):
        if index == 0:
            redacted = pattern.sub(r"\1 ***", redacted)
        elif index == 3:
            redacted = pattern.sub(r"\1***@", redacted)
        else:
            redacted = pattern.sub(r"\1***", redacted)
    return redacted


def redact_receipt_value(value: Any, *, key: str | None = None) -> Any:
    """Return stable JSON-safe receipt material with secret values removed."""
    if key and _SENSITIVE_KEY_RE.search(str(key)):
        return "***" if value not in (None, "", [], {}, ()) else value
    if isinstance(value, Mapping):
        return {
            str(item_key): redact_receipt_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_receipt_value(item) for item in value]
    if isinstance(value, bytes):
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, str):
        return _redact_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_string(str(value))


def _iso_timestamp(value: str | None, *, field_name: str, required: bool) -> str | None:
    normalized = str(value or "").strip() or None
    if normalized is None:
        if required:
            raise ValueError(f"{field_name} is required")
        return None
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


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
    artifact_refs: Sequence[str] = ()
    observations: Sequence[Mapping[str, Any]] = ()
    errors: Sequence[str] = ()

    def __post_init__(self) -> None:
        owner_scan = str(self.scan_id or "").strip() or None
        owner_hunt = str(self.hunt_id or "").strip() or None
        if not owner_scan and not owner_hunt:
            raise ValueError("capability receipt must belong to a scan or hunt")
        status = str(self.status or "").strip().lower()
        if not _STATUS_RE.fullmatch(status):
            raise ValueError("status must be a bounded machine-readable code")
        if self.partial and status in {"completed", "success", "succeeded"}:
            raise ValueError("partial execution cannot claim a successful terminal status")
        if self.timed_out and not self.partial:
            raise ValueError("timed out execution must be marked partial")
        digest = str(self.input_digest or "").strip().lower()
        if not _HEX_64_RE.fullmatch(digest):
            raise ValueError("input_digest must be 64 lowercase hex characters")

        reservation_id = str(self.budget_reservation_id or "").strip() or None
        reservation_state = str(self.budget_reservation_state or "").strip().lower() or None
        if reservation_state and not reservation_id:
            raise ValueError("budget_reservation_state requires budget_reservation_id")
        if reservation_id and reservation_state not in _TERMINAL_RESERVATION_STATES:
            raise ValueError("capability receipt requires a terminal budget reservation state")

        reserved = _normalize_budget(self.budget_reserved, allow_zero=False)
        consumed = _normalize_budget(self.budget_consumed, allow_zero=True)
        if set(consumed) - set(reserved):
            raise ValueError("budget_consumed contains dimensions absent from budget_reserved")
        for kind, amount in consumed.items():
            if amount > reserved[kind]:
                raise ValueError(f"budget_consumed exceeds the reservation for {kind}")
        if reservation_id and not reserved:
            raise ValueError("budget reservation linkage requires budget_reserved")

        started = _iso_timestamp(self.started_at, field_name="started_at", required=True)
        finished = _iso_timestamp(self.finished_at, field_name="finished_at", required=False)
        if finished and datetime.fromisoformat(finished) < datetime.fromisoformat(started):
            raise ValueError("finished_at must not be earlier than started_at")

        artifact_refs = tuple(dict.fromkeys(
            str(item).strip() for item in self.artifact_refs if str(item).strip()
        ))
        observations = tuple(
            redact_receipt_value(dict(item))
            for item in self.observations
            if isinstance(item, Mapping)
        )
        errors = tuple(_redact_string(str(item))[:2_000] for item in self.errors if str(item))

        object.__setattr__(self, "scan_id", owner_scan)
        object.__setattr__(self, "hunt_id", owner_hunt)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "input_digest", digest)
        object.__setattr__(self, "budget_reservation_id", reservation_id)
        object.__setattr__(self, "budget_reservation_state", reservation_state)
        object.__setattr__(self, "budget_reserved", reserved)
        object.__setattr__(self, "budget_consumed", consumed)
        object.__setattr__(
            self, "redacted_execution", redact_receipt_value(dict(self.redacted_execution or {}))
        )
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "finished_at", finished)
        object.__setattr__(self, "artifact_refs", artifact_refs)
        object.__setattr__(self, "observations", observations)
        object.__setattr__(self, "errors", errors)

    def canonical_dict(self) -> dict[str, Any]:
        """Stable JSON-safe receipt material used for persistence and hashing."""
        return {
            "receipt_id": self.receipt_id,
            "capability_name": self.capability_name,
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "target_id": self.target_id,
            "scan_id": self.scan_id,
            "hunt_id": self.hunt_id,
            "worker_id": self.worker_id,
            "scope_receipt_id": self.scope_receipt_id,
            "approval_receipt_id": self.approval_receipt_id,
            "status": self.status,
            "partial": bool(self.partial),
            "timed_out": bool(self.timed_out),
            "input_digest": self.input_digest,
            "parser_version": self.parser_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "redacted_execution": redact_receipt_value(self.redacted_execution),
            "budget_reservation_id": self.budget_reservation_id,
            "budget_reservation_state": self.budget_reservation_state,
            "budget_reserved": dict(self.budget_reserved),
            "budget_consumed": dict(self.budget_consumed),
            "output_artifact_id": self.output_artifact_id,
            "artifact_refs": list(self.artifact_refs),
            "observations": [redact_receipt_value(item) for item in self.observations],
            "errors": list(self.errors),
        }

    @property
    def receipt_hash(self) -> str:
        encoded = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def public_dict(self) -> dict[str, Any]:
        return {**self.canonical_dict(), "receipt_hash": self.receipt_hash}
