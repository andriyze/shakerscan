"""Generic, content-addressed terminal result envelope for Scan actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping
import uuid

try:  # Prefer one class identity when imported as api.scan.* in host-side tests.
    from ..runtime.budgets import BUDGET_DIMENSIONS
    from ..runtime.observation_manifests import ObservationManifestReference
except (ImportError, ModuleNotFoundError):  # imported as top-level scan.* by workers
    from runtime.budgets import BUDGET_DIMENSIONS
    from runtime.observation_manifests import ObservationManifestReference

from .action_plan import ScanAction


SCAN_CAPABILITY_RESULT_SCHEMA = "scan-capability-result/v1"
CAPABILITY_RECEIPT_REFERENCE_SCHEMA = "capability-receipt-reference/v1"
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:/-]{0,199}$")


class CapabilityResultStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class CapabilityResultReason(str, Enum):
    POLICY_DISABLED = "policy_disabled"
    INSUFFICIENT_PLAN_BUDGET = "insufficient_plan_budget"
    DEPENDENCY_FAILED = "dependency_failed"
    DEPENDENCY_PRIVATE_STATE_UNAVAILABLE = "dependency_private_state_unavailable"
    PLACEMENT_UNAVAILABLE = "placement_unavailable"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_REVOKED = "authorization_revoked"
    SCOPE_INVALID = "scope_invalid"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    ADAPTER_FAILED = "adapter_failed"
    PARSER_FAILED = "parser_failed"
    OUTPUT_TRUNCATED = "output_truncated"
    MANIFEST_UNAVAILABLE = "manifest_unavailable"
    UNSUPPORTED_OUTPUT_SCHEMA = "unsupported_output_schema"
    NOT_APPLICABLE = "not_applicable"


class CapabilityResultError(ValueError):
    """A result is malformed, inconsistent, or detached from action authority."""


def _hex_digest(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HEX_64_RE.fullmatch(normalized):
        raise CapabilityResultError(f"{name} must be 64 lowercase hex characters")
    return normalized


def _token(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip()
    if not _TOKEN_RE.fullmatch(normalized):
        raise CapabilityResultError(f"{name} is invalid")
    return normalized


def _budget(value: Mapping[str, Any], *, name: str) -> Mapping[str, int]:
    normalized: dict[str, int] = {}
    for raw_kind, raw_amount in dict(value or {}).items():
        kind = str(raw_kind or "").strip()
        if kind not in BUDGET_DIMENSIONS:
            raise CapabilityResultError(f"unknown {name} dimension: {kind}")
        if isinstance(raw_amount, bool) or not isinstance(raw_amount, int) or raw_amount < 0:
            raise CapabilityResultError(f"{name} {kind} must be a non-negative integer")
        normalized[kind] = raw_amount
    return MappingProxyType({key: normalized[key] for key in sorted(normalized)})


@dataclass(frozen=True)
class CapabilityReceiptReference:
    receipt_id: str
    receipt_hash: str
    schema_version: str = CAPABILITY_RECEIPT_REFERENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != CAPABILITY_RECEIPT_REFERENCE_SCHEMA:
            raise CapabilityResultError("unsupported capability receipt reference schema")
        try:
            receipt_id = str(uuid.UUID(str(self.receipt_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise CapabilityResultError("receipt_id must be a UUID") from exc
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_hash", _hex_digest(
            self.receipt_hash, name="receipt_hash",
        ))

    def canonical_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "receipt_hash": self.receipt_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityReceiptReference":
        expected = {"schema_version", "receipt_id", "receipt_hash"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise CapabilityResultError("capability receipt reference fields are invalid")
        return cls(**dict(value))


@dataclass(frozen=True)
class CapabilityResultReference:
    action_id: str
    action_digest: str
    capability_name: str
    adapter_name: str
    adapter_version: str
    output_schema: str
    status: CapabilityResultStatus | str
    partial: bool
    timed_out: bool
    reason_code: CapabilityResultReason | str | None
    receipt_ref: CapabilityReceiptReference
    observation_manifest_ref: ObservationManifestReference | None
    budget_reserved: Mapping[str, int]
    budget_consumed: Mapping[str, int]
    schema_version: str = SCAN_CAPABILITY_RESULT_SCHEMA
    result_digest: str | None = field(default=None, compare=True)

    def __post_init__(self) -> None:
        if self.schema_version != SCAN_CAPABILITY_RESULT_SCHEMA:
            raise CapabilityResultError("unsupported Scan capability result schema")
        action_id = _token(self.action_id, name="action_id")
        status = (
            self.status
            if isinstance(self.status, CapabilityResultStatus)
            else CapabilityResultStatus(str(self.status or "").strip())
        )
        reason = self.reason_code
        if reason is not None and not isinstance(reason, CapabilityResultReason):
            reason = CapabilityResultReason(str(reason or "").strip())
        if not isinstance(self.partial, bool) or not isinstance(self.timed_out, bool):
            raise CapabilityResultError("partial and timed_out must be booleans")
        if status is CapabilityResultStatus.SUCCESS:
            if self.partial or self.timed_out or reason is not None:
                raise CapabilityResultError("successful result cannot be partial or have a reason")
            if self.observation_manifest_ref is None:
                raise CapabilityResultError("successful result requires an observation manifest")
        else:
            if reason is None:
                raise CapabilityResultError("non-success result requires a stable reason_code")
        if status in {CapabilityResultStatus.PARTIAL, CapabilityResultStatus.TIMED_OUT} and not self.partial:
            raise CapabilityResultError("partial/timed-out status must set partial")
        if self.timed_out and status not in {
            CapabilityResultStatus.PARTIAL, CapabilityResultStatus.TIMED_OUT,
        }:
            raise CapabilityResultError("timed_out is inconsistent with result status")
        if status is CapabilityResultStatus.TIMED_OUT and not self.timed_out:
            raise CapabilityResultError("timed_out status must set timed_out")

        reserved = _budget(self.budget_reserved, name="budget_reserved")
        consumed = _budget(self.budget_consumed, name="budget_consumed")
        if set(consumed) - set(reserved):
            raise CapabilityResultError("consumed budget contains unreserved dimensions")
        for kind, amount in consumed.items():
            if amount > reserved[kind]:
                raise CapabilityResultError(f"consumed budget exceeds reservation for {kind}")

        object.__setattr__(self, "action_id", action_id)
        object.__setattr__(self, "action_digest", _hex_digest(
            self.action_digest, name="action_digest",
        ))
        object.__setattr__(self, "capability_name", _token(
            self.capability_name, name="capability_name",
        ))
        object.__setattr__(self, "adapter_name", _token(
            self.adapter_name, name="adapter_name",
        ))
        object.__setattr__(self, "adapter_version", _token(
            self.adapter_version, name="adapter_version",
        ))
        object.__setattr__(self, "output_schema", _token(
            self.output_schema, name="output_schema",
        ))
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason_code", reason)
        object.__setattr__(self, "budget_reserved", reserved)
        object.__setattr__(self, "budget_consumed", consumed)
        expected = hashlib.sha256(json.dumps(
            self.digest_material(), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")).hexdigest()
        supplied = self.result_digest
        if supplied is not None and _hex_digest(supplied, name="result_digest") != expected:
            raise CapabilityResultError("result_digest does not match canonical result")
        object.__setattr__(self, "result_digest", expected)

    def digest_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "capability_name": self.capability_name,
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "output_schema": self.output_schema,
            "status": self.status.value,
            "partial": self.partial,
            "timed_out": self.timed_out,
            "reason_code": self.reason_code.value if self.reason_code is not None else None,
            "receipt_ref": self.receipt_ref.canonical_dict(),
            "observation_manifest_ref": (
                self.observation_manifest_ref.canonical_dict()
                if self.observation_manifest_ref is not None else None
            ),
            "budget_reserved": dict(self.budget_reserved),
            "budget_consumed": dict(self.budget_consumed),
        }

    def canonical_dict(self) -> dict[str, Any]:
        return {**self.digest_material(), "result_digest": self.result_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityResultReference":
        expected = {
            "schema_version", "action_id", "action_digest", "capability_name",
            "adapter_name", "adapter_version", "output_schema", "status", "partial",
            "timed_out", "reason_code", "receipt_ref", "observation_manifest_ref",
            "budget_reserved", "budget_consumed", "result_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise CapabilityResultError("Scan capability result fields are invalid")
        receipt = value.get("receipt_ref")
        manifest = value.get("observation_manifest_ref")
        return cls(
            **{
                **dict(value),
                "receipt_ref": CapabilityReceiptReference.from_dict(receipt),
                "observation_manifest_ref": (
                    ObservationManifestReference.from_dict(manifest)
                    if manifest is not None else None
                ),
            }
        )


def placement_from_stored_result(
    *, action: ScanAction, stored: CapabilityResultReference | Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one stored generic result and return its content-free placement."""
    result = (
        stored
        if isinstance(stored, CapabilityResultReference)
        else CapabilityResultReference.from_dict(stored)
    )
    if result.action_id != action.action_id or result.action_digest != action.action_digest:
        raise CapabilityResultError("stored result is detached from Scan action authority")
    if result.capability_name != action.capability_name:
        raise CapabilityResultError("stored result capability differs from its Scan action")
    if result.output_schema != action.output_schema:
        raise CapabilityResultError("stored result schema differs from its Scan action")
    return result.canonical_dict()
