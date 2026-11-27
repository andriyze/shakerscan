"""Canonical deterministic Scan execution plan.

The plan deliberately has one engine identity (``scan``). Resource depth and active
permission are data in the immutable policy/budget snapshot, never alternate scanner
identities. Legacy executor aliases live outside this model while the old worker is
being retired.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Mapping

try:
    from runtime.models import ScanBudget, ScanPolicy
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.models import ScanBudget, ScanPolicy


SCAN_EXECUTION_SCHEMA = "scan-execution-plan/v1"
SCAN_ENGINE = "scan"
SCAN_GENERATION = "v2"


def _json_safe(value: Any) -> Any:
    """Return a stable JSON-compatible value without mutating the source model."""
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


# The exact key set canonical_dict() emits. Validators must derive from this
# rather than restating it, so a new plan field cannot silently invalidate every
# execution envelope.
SCAN_EXECUTION_PLAN_CANONICAL_FIELDS: tuple[str, ...] = (
    "schema_version", "generation", "engine", "budget_profile", "family_preset",
    "requested_families", "resolved_families", "policy", "budget",
)


@dataclass(frozen=True)
class ScanExecutionPlan:
    """Immutable, reproducible authority for one deterministic Scan run."""

    policy: ScanPolicy
    budget_profile: str
    budget: ScanBudget
    family_preset: str = "custom"
    requested_families: tuple[str, ...] = ()
    resolved_families: tuple[str, ...] = ()
    generation: str = SCAN_GENERATION
    engine: str = SCAN_ENGINE
    schema_version: str = SCAN_EXECUTION_SCHEMA

    def __post_init__(self) -> None:
        if self.generation != SCAN_GENERATION:
            raise ValueError(f"scan generation must be {SCAN_GENERATION}")
        if self.engine != SCAN_ENGINE:
            raise ValueError(f"scan engine must be {SCAN_ENGINE}")
        if self.schema_version != SCAN_EXECUTION_SCHEMA:
            raise ValueError(f"scan schema_version must be {SCAN_EXECUTION_SCHEMA}")
        profile = str(self.budget_profile or "").strip().lower()
        if not profile:
            raise ValueError("budget_profile must not be empty")
        object.__setattr__(self, "budget_profile", profile)
        preset = str(self.family_preset or "").strip().lower()
        if preset not in {"passive", "standard_active", "custom"}:
            raise ValueError("family_preset must be passive, standard_active, or custom")
        requested = tuple(dict.fromkeys(str(item).strip().lower() for item in self.requested_families if str(item).strip()))
        resolved = tuple(dict.fromkeys(str(item).strip().lower() for item in self.resolved_families if str(item).strip()))
        # Compatibility for server-authored tests and stored adapters that build
        # the plan directly: a non-empty legacy include list is already an exact
        # allowlist, so preserve it in the new explicit fields.
        if not resolved and self.policy.include_families:
            resolved = tuple(self.policy.include_families)
        object.__setattr__(self, "family_preset", preset)
        object.__setattr__(self, "requested_families", requested)
        object.__setattr__(self, "resolved_families", resolved)

    def canonical_dict(self) -> dict[str, Any]:
        """Canonical persisted/public representation; contains no legacy mode alias."""
        return {
            "schema_version": self.schema_version,
            "generation": self.generation,
            "engine": self.engine,
            "budget_profile": self.budget_profile,
            "family_preset": self.family_preset,
            "requested_families": list(self.requested_families),
            "resolved_families": list(self.resolved_families),
            "policy": _json_safe(asdict(self.policy)),
            "budget": _json_safe(asdict(self.budget)),
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def option_metadata(self) -> dict[str, Any]:
        return {
            "scan_generation": self.generation,
            "scan_engine": self.engine,
            "scan_execution_plan_schema": self.schema_version,
            "scan_execution_plan_digest": self.digest,
            "scan_execution_plan": self.canonical_dict(),
            # Existing readers retain these flattened snapshots during migration.
            "scan_policy": _json_safe(asdict(self.policy)),
            "resolved_scan_budget": _json_safe(asdict(self.budget)),
            "budget_profile": self.budget_profile,
        }
