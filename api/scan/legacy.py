"""Legacy DAST input translation at the public API boundary.

Legacy names are accepted only at the API boundary. They translate to a canonical
Scan policy/budget and never enter worker execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

LEGACY_SCAN_MAPPING: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    "quick": {"budget_profile": "fast", "active_testing": False},
    "standard": {"budget_profile": "balanced", "active_testing": False},
    "deep": {"budget_profile": "thorough", "active_testing": False},
    "full": {"budget_profile": "thorough", "active_testing": True},
    "aggressive": {"budget_profile": "thorough", "active_testing": True},
    "smart": {"budget_profile": "thorough", "active_testing": True},
})


@dataclass(frozen=True)
class LegacyScanTranslation:
    legacy_scan_type: str
    budget_profile: str
    active_testing: bool
    advanced: Mapping[str, Any] = field(default_factory=dict)

    def deprecation(self) -> Mapping[str, Any]:
        return {
            "field": "scan_type",
            "value": self.legacy_scan_type,
            "replacement": {
                "active_testing": self.active_testing,
                "budget_profile": self.budget_profile,
            },
        }


def translate_legacy_scan_type(value: str | None) -> LegacyScanTranslation | None:
    legacy = str(value or "").strip().lower() or None
    if legacy is None:
        return None
    try:
        mapping = LEGACY_SCAN_MAPPING[legacy]
    except KeyError as exc:
        raise ValueError("legacy scan_type is invalid") from exc
    return LegacyScanTranslation(
        legacy_scan_type=legacy,
        budget_profile=str(mapping["budget_profile"]),
        active_testing=bool(mapping["active_testing"]),
        advanced=MappingProxyType(dict(mapping.get("advanced") or {})),
    )
